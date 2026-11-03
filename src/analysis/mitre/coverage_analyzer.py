"""
MITRE ATT&CK Coverage Analyzer

Real-time coverage analysis during artifact processing.
Tracks evidence, calculates coverage, generates standalone reports.

Author: Dernvale DF Acceleration Suite
Version: 2.1.0
"""

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Any
from collections import defaultdict
from dataclasses import dataclass, asdict

from .technique_mapper import TechniqueMapper
from .attck_updater import MitreAttackUpdater


@dataclass
class Evidence:
    """Evidence supporting a technique detection."""

    artifact_type: str
    artifact_path: str
    timestamp: str
    confidence: float
    context: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class TechniqueDetection:
    """A detected MITRE ATT&CK technique with evidence."""

    technique_id: str
    technique_name: str
    tactics: List[str]
    confidence: float
    detection_count: int
    first_seen: str
    last_seen: str
    evidence: List[Evidence]

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactics": self.tactics,
            "confidence": self.confidence,
            "detection_count": self.detection_count,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "evidence": [e.to_dict() for e in self.evidence],
        }


class CoverageDatabase:
    """
    SQLite database for storing coverage data during analysis.

    Tables:
    - techniques: Detected techniques with metadata
    - evidence: Evidence supporting each technique
    - artifacts: Processed artifacts
    - statistics: Coverage statistics over time
    """

    def __init__(self, db_path: str):
        """
        Initialize coverage database.

        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self.conn = None
        self._create_tables()

    def _create_tables(self):
        """Create database tables."""
        self.conn = sqlite3.connect(self.db_path)
        cursor = self.conn.cursor()

        # Techniques table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS techniques (
                technique_id TEXT PRIMARY KEY,
                technique_name TEXT,
                tactics TEXT,
                confidence REAL,
                detection_count INTEGER,
                first_seen TEXT,
                last_seen TEXT
            )
        """
        )

        # Evidence table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                technique_id TEXT,
                artifact_type TEXT,
                artifact_path TEXT,
                timestamp TEXT,
                confidence REAL,
                context TEXT,
                metadata TEXT,
                FOREIGN KEY (technique_id) REFERENCES techniques(technique_id)
            )
        """
        )

        # Artifacts table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS artifacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                artifact_type TEXT,
                artifact_path TEXT,
                processed_timestamp TEXT,
                technique_count INTEGER
            )
        """
        )

        # Statistics table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS statistics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                total_techniques INTEGER,
                detected_techniques INTEGER,
                coverage_percentage REAL,
                total_artifacts INTEGER
            )
        """
        )

        self.conn.commit()

    def add_technique(self, detection: TechniqueDetection):
        """Add or update technique detection."""
        cursor = self.conn.cursor()

        # Check if technique exists
        cursor.execute(
            "SELECT detection_count, first_seen FROM techniques WHERE technique_id = ?",
            (detection.technique_id,),
        )
        existing = cursor.fetchone()

        if existing:
            # Update existing
            new_count = existing[0] + 1
            cursor.execute(
                """
                UPDATE techniques
                SET detection_count = ?,
                    confidence = ?,
                    last_seen = ?
                WHERE technique_id = ?
            """,
                (new_count, detection.confidence, detection.last_seen, detection.technique_id),
            )
        else:
            # Insert new
            cursor.execute(
                """
                INSERT INTO techniques
                (technique_id, technique_name, tactics, confidence, detection_count, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    detection.technique_id,
                    detection.technique_name,
                    json.dumps(detection.tactics),
                    detection.confidence,
                    detection.detection_count,
                    detection.first_seen,
                    detection.last_seen,
                ),
            )

        self.conn.commit()

    def add_evidence(self, technique_id: str, evidence: Evidence):
        """Add evidence for a technique."""
        cursor = self.conn.cursor()

        cursor.execute(
            """
            INSERT INTO evidence
            (technique_id, artifact_type, artifact_path, timestamp, confidence, context, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
            (
                technique_id,
                evidence.artifact_type,
                evidence.artifact_path,
                evidence.timestamp,
                evidence.confidence,
                evidence.context,
                json.dumps(evidence.metadata) if evidence.metadata else None,
            ),
        )

        self.conn.commit()

    def add_artifact(self, artifact_type: str, artifact_path: str, technique_count: int):
        """Record processed artifact."""
        cursor = self.conn.cursor()

        cursor.execute(
            """
            INSERT INTO artifacts
            (artifact_type, artifact_path, processed_timestamp, technique_count)
            VALUES (?, ?, ?, ?)
        """,
            (artifact_type, artifact_path, datetime.utcnow().isoformat(), technique_count),
        )

        self.conn.commit()

    def add_statistics(self, stats: dict):
        """Record coverage statistics snapshot."""
        cursor = self.conn.cursor()

        cursor.execute(
            """
            INSERT INTO statistics
            (timestamp, total_techniques, detected_techniques, coverage_percentage, total_artifacts)
            VALUES (?, ?, ?, ?, ?)
        """,
            (
                datetime.utcnow().isoformat(),
                stats["total_techniques"],
                stats["detected_techniques"],
                stats["coverage_percentage"],
                stats["total_artifacts"],
            ),
        )

        self.conn.commit()

    def get_all_techniques(self) -> List[TechniqueDetection]:
        """Get all detected techniques."""
        cursor = self.conn.cursor()

        cursor.execute(
            """
            SELECT technique_id, technique_name, tactics, confidence,
                   detection_count, first_seen, last_seen
            FROM techniques
            ORDER BY confidence DESC, detection_count DESC
        """
        )

        techniques = []
        for row in cursor.fetchall():
            # Get evidence for this technique
            cursor.execute(
                """
                SELECT artifact_type, artifact_path, timestamp, confidence, context, metadata
                FROM evidence
                WHERE technique_id = ?
            """,
                (row[0],),
            )

            evidence_rows = cursor.fetchall()
            evidence = [
                Evidence(
                    artifact_type=e[0],
                    artifact_path=e[1],
                    timestamp=e[2],
                    confidence=e[3],
                    context=e[4],
                    metadata=json.loads(e[5]) if e[5] else None,
                )
                for e in evidence_rows
            ]

            techniques.append(
                TechniqueDetection(
                    technique_id=row[0],
                    technique_name=row[1],
                    tactics=json.loads(row[2]),
                    confidence=row[3],
                    detection_count=row[4],
                    first_seen=row[5],
                    last_seen=row[6],
                    evidence=evidence,
                )
            )

        return techniques

    def get_statistics(self) -> dict:
        """Get current coverage statistics."""
        cursor = self.conn.cursor()

        # Get technique counts
        cursor.execute("SELECT COUNT(*) FROM techniques")
        detected_count = cursor.fetchone()[0]

        # Get artifact count
        cursor.execute("SELECT COUNT(*) FROM artifacts")
        artifact_count = cursor.fetchone()[0]

        # Get confidence distribution
        cursor.execute(
            """
            SELECT
                SUM(CASE WHEN confidence >= 0.8 THEN 1 ELSE 0 END) as high,
                SUM(CASE WHEN confidence >= 0.5 AND confidence < 0.8 THEN 1 ELSE 0 END) as medium,
                SUM(CASE WHEN confidence < 0.5 THEN 1 ELSE 0 END) as low
            FROM techniques
        """
        )
        conf_dist = cursor.fetchone()

        return {
            "detected_techniques": detected_count,
            "total_artifacts": artifact_count,
            "confidence_distribution": {
                "high": conf_dist[0] or 0,
                "medium": conf_dist[1] or 0,
                "low": conf_dist[2] or 0,
            },
        }

    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()


class MitreCoverageAnalyzer:
    """
    Real-time MITRE ATT&CK coverage analyzer.

    Features:
    - Real-time technique detection during artifact processing
    - Evidence tracking with timestamps and confidence
    - Coverage calculation and statistics
    - Multiple export formats (JSON, HTML, CSV, Navigator)
    - SIEM-ready data export
    - Standalone dashboard generation
    """

    def __init__(self, case_id: str, output_dir: str, auto_update: bool = True):
        """
        Initialize coverage analyzer.

        Args:
            case_id: Case/investigation identifier
            output_dir: Output directory for reports and database
            auto_update: Auto-update ATT&CK data on init
        """
        self.case_id = case_id
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Create MITRE subdirectory
        self.mitre_dir = self.output_dir / "mitre"
        self.mitre_dir.mkdir(exist_ok=True)

        # Initialize components
        self.updater = MitreAttackUpdater()
        self.mapper = TechniqueMapper(self.updater)

        if auto_update:
            self.updater.update_local_cache()

        self.attck_data = self.updater.load_cached_data()

        # Initialize database
        db_path = str(self.mitre_dir / f"{case_id}_coverage.db")
        self.db = CoverageDatabase(db_path)

        # Track processing
        self.start_time = datetime.utcnow()
        self.artifact_count = 0

    def analyze_artifact(
        self,
        artifact_type: str,
        artifact_path: str,
        artifact_data: Optional[dict] = None,
        context: Optional[str] = None,
    ) -> List[TechniqueDetection]:
        """
        Analyze artifact and update coverage in real-time.

        Args:
            artifact_type: Type of artifact
            artifact_path: Path to artifact file
            artifact_data: Optional artifact metadata
            context: Optional context (command line, file content, etc.)

        Returns:
            List of detected techniques
        """
        # Map artifact to techniques
        mappings = self.mapper.map_artifact_to_techniques(
            artifact_type=artifact_type, artifact_data=artifact_data, context=context
        )

        detections = []
        now = datetime.utcnow().isoformat() + "Z"

        for mapping in mappings:
            # Create evidence
            evidence = Evidence(
                artifact_type=artifact_type,
                artifact_path=artifact_path,
                timestamp=now,
                confidence=mapping["confidence"],
                context=context,
                metadata=artifact_data,
            )

            # Create or update detection
            detection = TechniqueDetection(
                technique_id=mapping["id"],
                technique_name=mapping["name"],
                tactics=mapping["tactics"],
                confidence=mapping["confidence"],
                detection_count=1,
                first_seen=now,
                last_seen=now,
                evidence=[evidence],
            )

            # Store in database
            self.db.add_technique(detection)
            self.db.add_evidence(detection.technique_id, evidence)

            detections.append(detection)

        # Record processed artifact
        self.db.add_artifact(artifact_type, artifact_path, len(detections))
        self.artifact_count += 1

        return detections

    def generate_coverage_report(self) -> dict:
        """
        Generate comprehensive coverage report.

        Returns:
            Coverage report with statistics and technique details
        """
        # Get all detections
        detections = self.db.get_all_techniques()

        # Calculate statistics
        stats = self._calculate_coverage_statistics(detections)

        # Build report
        report = {
            "case_id": self.case_id,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "attck_version": self.attck_data.get("version", "unknown"),
            "analysis_duration": (datetime.utcnow() - self.start_time).total_seconds(),
            "statistics": stats,
            "techniques": [d.to_dict() for d in detections],
            "tactics_summary": self._get_tactics_summary(detections),
            "evidence_map": self._get_evidence_map(detections),
        }

        # Save statistics snapshot
        self.db.add_statistics(stats)

        return report

    def _calculate_coverage_statistics(self, detections: List[TechniqueDetection]) -> dict:
        """Calculate coverage statistics."""
        total_techniques = len(self.attck_data.get("techniques", {}))
        detected_count = len(detections)

        # Confidence distribution
        high_conf = sum(1 for d in detections if d.confidence >= 0.8)
        medium_conf = sum(1 for d in detections if 0.5 <= d.confidence < 0.8)
        low_conf = sum(1 for d in detections if d.confidence < 0.5)

        # Tactic coverage
        tactics_with_coverage = len(self._get_tactics_summary(detections))
        total_tactics = len(self.attck_data.get("tactics", {}))

        return {
            "total_techniques": total_techniques,
            "detected_techniques": detected_count,
            "coverage_percentage": (
                (detected_count / total_techniques * 100) if total_techniques > 0 else 0
            ),
            "total_tactics": total_tactics,
            "tactics_with_coverage": tactics_with_coverage,
            "total_artifacts": self.artifact_count,
            "confidence_distribution": {"high": high_conf, "medium": medium_conf, "low": low_conf},
        }

    def _get_tactics_summary(self, detections: List[TechniqueDetection]) -> dict:
        """Get tactic-level coverage summary."""
        tactic_summary = defaultdict(lambda: {"techniques": [], "count": 0})

        for detection in detections:
            for tactic in detection.tactics:
                tactic_summary[tactic]["techniques"].append(detection.technique_id)
                tactic_summary[tactic]["count"] += 1

        return dict(tactic_summary)

    def _get_evidence_map(self, detections: List[TechniqueDetection]) -> dict:
        """Get artifact-to-technique mapping."""
        evidence_map = defaultdict(list)

        for detection in detections:
            for evidence in detection.evidence:
                evidence_map[evidence.artifact_path].append(
                    {
                        "technique_id": detection.technique_id,
                        "technique_name": detection.technique_name,
                        "confidence": evidence.confidence,
                    }
                )

        return dict(evidence_map)

    def export_json(self, output_file: Optional[str] = None) -> str:
        """
        Export coverage report as JSON.

        Args:
            output_file: Output file path (optional)

        Returns:
            Path to exported file
        """
        if not output_file:
            output_file = str(self.mitre_dir / "coverage.json")

        report = self.generate_coverage_report()

        with open(output_file, "w") as f:
            json.dump(report, f, indent=2)

        return output_file

    def export_csv(self, output_dir: Optional[str] = None) -> dict:
        """
        Export coverage data as CSV files.

        Args:
            output_dir: Output directory (optional)

        Returns:
            Dictionary with paths to generated CSV files
        """
        import csv

        if not output_dir:
            output_dir = str(self.mitre_dir)

        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        report = self.generate_coverage_report()
        files = {}

        # Techniques CSV
        techniques_file = output_path / "techniques.csv"
        with open(techniques_file, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "Technique ID",
                    "Technique Name",
                    "Tactics",
                    "Confidence",
                    "Detection Count",
                    "First Seen",
                    "Last Seen",
                    "Evidence Count",
                ]
            )

            for tech in report["techniques"]:
                writer.writerow(
                    [
                        tech["technique_id"],
                        tech["technique_name"],
                        ", ".join(tech["tactics"]),
                        f"{tech['confidence']:.2f}",
                        tech["detection_count"],
                        tech["first_seen"],
                        tech["last_seen"],
                        len(tech["evidence"]),
                    ]
                )

        files["techniques"] = str(techniques_file)

        # Tactics summary CSV
        tactics_file = output_path / "tactics_summary.csv"
        with open(tactics_file, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Tactic", "Technique Count", "Techniques"])

            for tactic, data in report["tactics_summary"].items():
                writer.writerow([tactic, data["count"], ", ".join(data["techniques"])])

        files["tactics_summary"] = str(tactics_file)

        # Evidence map CSV
        evidence_file = output_path / "evidence_map.csv"
        with open(evidence_file, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Artifact Path", "Technique ID", "Technique Name", "Confidence"])

            for artifact_path, techniques in report["evidence_map"].items():
                for tech in techniques:
                    writer.writerow(
                        [
                            artifact_path,
                            tech["technique_id"],
                            tech["technique_name"],
                            f"{tech['confidence']:.2f}",
                        ]
                    )

        files["evidence_map"] = str(evidence_file)

        return files

    def export_for_siem(self, siem_type: str) -> List[dict]:
        """
        Export coverage data for SIEM ingestion.

        Args:
            siem_type: 'splunk' or 'elastic'

        Returns:
            List of events/documents ready for SIEM
        """
        report = self.generate_coverage_report()
        events = []

        for technique in report["techniques"]:
            if siem_type == "splunk":
                # Splunk HEC format
                for evidence in technique["evidence"]:
                    event = {
                        "time": evidence["timestamp"],
                        "source": "dernvale:mitre",
                        "sourcetype": "mitre:coverage",
                        "event": {
                            "case_id": self.case_id,
                            "technique_id": technique["technique_id"],
                            "technique_name": technique["technique_name"],
                            "tactics": technique["tactics"],
                            "confidence": technique["confidence"],
                            "artifact_type": evidence["artifact_type"],
                            "artifact_path": evidence["artifact_path"],
                            "context": evidence.get("context", ""),
                        },
                    }
                    events.append(event)

            elif siem_type == "elastic":
                # Elasticsearch format
                for evidence in technique["evidence"]:
                    doc = {
                        "@timestamp": evidence["timestamp"],
                        "case_id": self.case_id,
                        "mitre": {
                            "technique_id": technique["technique_id"],
                            "technique_name": technique["technique_name"],
                            "tactics": technique["tactics"],
                            "confidence": technique["confidence"],
                        },
                        "artifact": {
                            "type": evidence["artifact_type"],
                            "path": evidence["artifact_path"],
                            "context": evidence.get("context", ""),
                        },
                    }
                    events.append(doc)

        return events

    def close(self):
        """Close coverage analyzer and database."""
        self.db.close()


# Convenience functions


def analyze_artifact(
    case_id: str,
    output_dir: str,
    artifact_type: str,
    artifact_path: str,
    artifact_data: Optional[dict] = None,
    context: Optional[str] = None,
) -> List[TechniqueDetection]:
    """
    Convenience function to analyze a single artifact.

    Args:
        case_id: Case identifier
        output_dir: Output directory
        artifact_type: Artifact type
        artifact_path: Artifact path
        artifact_data: Optional metadata
        context: Optional context

    Returns:
        List of detected techniques
    """
    analyzer = MitreCoverageAnalyzer(case_id, output_dir)
    detections = analyzer.analyze_artifact(artifact_type, artifact_path, artifact_data, context)
    analyzer.close()

    return detections

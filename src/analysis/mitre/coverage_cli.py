#!/usr/bin/env python3
"""
MITRE Coverage Analysis CLI

Command-line interface for standalone coverage analysis.

Usage:
    python -m analysis.mitre.coverage_cli init CASE-001 /output
    python -m analysis.mitre.coverage_cli analyze CASE-001 /output prefetch /path/to/file
    python -m analysis.mitre.coverage_cli report CASE-001 /output
    python -m analysis.mitre.coverage_cli dashboard CASE-001 /output
    python -m analysis.mitre.coverage_cli export CASE-001 /output --format json,csv,html

Author: Rowanholt DF Acceleration Suite
Version: 2.1.0
"""

import argparse
import sys
import json
import logging
from pathlib import Path

from .coverage_analyzer import MitreCoverageAnalyzer
from .standalone_dashboard import generate_standalone_dashboard


def setup_logging(verbose: bool = False):
    """Setup logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def cmd_init(args):
    """Initialize coverage analysis for a case."""
    print(f"[*] Initializing coverage analysis for case: {args.case_id}")

    output_path = Path(args.output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Create analyzer (creates database)
    analyzer = MitreCoverageAnalyzer(args.case_id, args.output_dir)

    print(f"[+] Coverage analysis initialized")
    print(f"    Output directory: {analyzer.mitre_dir}")
    print(f"    Database: {analyzer.mitre_dir}/{args.case_id}_coverage.db")

    analyzer.close()


def cmd_analyze(args):
    """Analyze a single artifact."""
    print(f"[*] Analyzing artifact: {args.artifact_path}")

    # Parse optional data
    artifact_data = None
    if args.data:
        try:
            artifact_data = json.loads(args.data)
        except json.JSONDecodeError:
            print(f"[-] Invalid JSON in --data: {args.data}", file=sys.stderr)
            sys.exit(1)

    # Analyze artifact
    analyzer = MitreCoverageAnalyzer(args.case_id, args.output_dir, auto_update=False)

    detections = analyzer.analyze_artifact(
        artifact_type=args.artifact_type,
        artifact_path=args.artifact_path,
        artifact_data=artifact_data,
        context=args.context,
    )

    print(f"[+] Analysis complete")
    print(f"    Techniques detected: {len(detections)}")

    if detections and args.verbose:
        print("\n[*] Detected techniques:")
        for detection in detections:
            print(f"  {detection.technique_id}: {detection.technique_name}")
            print(f"    Confidence: {detection.confidence:.2f}")
            print(f"    Tactics: {', '.join(detection.tactics)}")
            print()

    analyzer.close()


def cmd_batch(args):
    """Analyze multiple artifacts from a file list."""
    print(f"[*] Starting batch analysis from: {args.artifact_list}")

    # Read artifact list
    with open(args.artifact_list, "r") as f:
        artifacts = [line.strip().split(",") for line in f if line.strip()]

    print(f"[*] Found {len(artifacts)} artifacts to process")

    # Initialize analyzer
    analyzer = MitreCoverageAnalyzer(args.case_id, args.output_dir, auto_update=False)

    # Process each artifact
    for i, artifact in enumerate(artifacts, 1):
        if len(artifact) < 2:
            print(f"[-] Skipping invalid line: {artifact}")
            continue

        artifact_type = artifact[0]
        artifact_path = artifact[1]
        context = artifact[2] if len(artifact) > 2 else None

        print(f"[{i}/{len(artifacts)}] Processing: {artifact_path}")

        try:
            detections = analyzer.analyze_artifact(
                artifact_type=artifact_type, artifact_path=artifact_path, context=context
            )

            if args.verbose and detections:
                print(f"  └─ Detected {len(detections)} technique(s)")

        except Exception as e:
            print(f"  └─ Error: {e}")

    print(f"\n[+] Batch analysis complete")

    # Show summary
    stats = analyzer.db.get_statistics()
    print(f"    Total artifacts processed: {stats['total_artifacts']}")
    print(f"    Unique techniques detected: {stats['detected_techniques']}")
    print(f"    High confidence: {stats['confidence_distribution']['high']}")
    print(f"    Medium confidence: {stats['confidence_distribution']['medium']}")
    print(f"    Low confidence: {stats['confidence_distribution']['low']}")

    analyzer.close()


def cmd_report(args):
    """Generate coverage report."""
    print(f"[*] Generating coverage report for: {args.case_id}")

    analyzer = MitreCoverageAnalyzer(args.case_id, args.output_dir, auto_update=False)

    report = analyzer.generate_coverage_report()

    # Print summary
    stats = report["statistics"]
    print(f"\n[+] Coverage Report")
    print(f"    Case: {report['case_id']}")
    print(f"    ATT&CK Version: {report['attck_version']}")
    print(f"    Analysis Duration: {report['analysis_duration']:.1f} seconds")
    print(f"\n[*] Statistics:")
    print(f"    Total Techniques: {stats['total_techniques']}")
    print(f"    Detected Techniques: {stats['detected_techniques']}")
    print(f"    Coverage: {stats['coverage_percentage']:.1f}%")
    print(f"    Artifacts Processed: {stats['total_artifacts']}")
    print(f"\n[*] Confidence Distribution:")
    print(f"    High (≥0.8): {stats['confidence_distribution']['high']}")
    print(f"    Medium (0.5-0.8): {stats['confidence_distribution']['medium']}")
    print(f"    Low (<0.5): {stats['confidence_distribution']['low']}")
    print(f"\n[*] Tactic Coverage:")
    print(f"    Tactics with detections: {stats['tactics_with_coverage']}/{stats['total_tactics']}")

    if args.detailed:
        print(f"\n[*] Top Techniques:")
        for i, tech in enumerate(report["techniques"][:10], 1):
            print(f"  {i}. {tech['technique_id']}: {tech['technique_name']}")
            print(
                f"     Confidence: {tech['confidence']:.2f} | Detections: {tech['detection_count']}"
            )

    analyzer.close()


def cmd_dashboard(args):
    """Generate standalone HTML dashboard."""
    print(f"[*] Generating standalone dashboard for: {args.case_id}")

    analyzer = MitreCoverageAnalyzer(args.case_id, args.output_dir, auto_update=False)

    # Generate coverage report
    report = analyzer.generate_coverage_report()

    # Generate dashboard
    output_file = args.output or str(analyzer.mitre_dir / "coverage.html")
    dashboard_path = generate_standalone_dashboard(report, output_file)

    print(f"[+] Dashboard generated: {dashboard_path}")
    print(f"    Open in browser: file://{Path(dashboard_path).absolute()}")

    analyzer.close()


def cmd_export(args):
    """Export coverage data in various formats."""
    print(f"[*] Exporting coverage data for: {args.case_id}")

    analyzer = MitreCoverageAnalyzer(args.case_id, args.output_dir, auto_update=False)

    formats = args.format.split(",") if args.format else ["json", "csv", "html"]
    exported = {}

    for fmt in formats:
        fmt = fmt.strip().lower()

        try:
            if fmt == "json":
                output_file = args.output or str(analyzer.mitre_dir / "coverage.json")
                path = analyzer.export_json(output_file)
                exported["json"] = path
                print(f"[+] JSON exported: {path}")

            elif fmt == "csv":
                output_dir = args.output or str(analyzer.mitre_dir)
                paths = analyzer.export_csv(output_dir)
                exported["csv"] = paths
                print(f"[+] CSV exported:")
                for name, path in paths.items():
                    print(f"    {name}: {path}")

            elif fmt == "html" or fmt == "dashboard":
                report = analyzer.generate_coverage_report()
                output_file = args.output or str(analyzer.mitre_dir / "coverage.html")
                path = generate_standalone_dashboard(report, output_file)
                exported["html"] = path
                print(f"[+] HTML dashboard exported: {path}")

            elif fmt == "splunk":
                events = analyzer.export_for_siem("splunk")
                output_file = args.output or str(analyzer.mitre_dir / "splunk_events.json")
                with open(output_file, "w") as f:
                    json.dump(events, f, indent=2)
                exported["splunk"] = output_file
                print(f"[+] Splunk HEC events exported: {output_file}")

            elif fmt == "elastic":
                docs = analyzer.export_for_siem("elastic")
                output_file = args.output or str(analyzer.mitre_dir / "elastic_docs.json")
                with open(output_file, "w") as f:
                    json.dump(docs, f, indent=2)
                exported["elastic"] = output_file
                print(f"[+] Elasticsearch documents exported: {output_file}")

            else:
                print(f"[-] Unknown format: {fmt}", file=sys.stderr)

        except Exception as e:
            print(f"[-] Error exporting {fmt}: {e}", file=sys.stderr)

    analyzer.close()

    return exported


def cmd_stats(args):
    """Show current coverage statistics."""
    print(f"[*] Coverage statistics for: {args.case_id}")

    analyzer = MitreCoverageAnalyzer(args.case_id, args.output_dir, auto_update=False)

    stats = analyzer.db.get_statistics()

    print(f"\n[*] Statistics:")
    print(f"    Techniques Detected: {stats['detected_techniques']}")
    print(f"    Artifacts Processed: {stats['total_artifacts']}")
    print(f"\n[*] Confidence Distribution:")
    print(f"    High (≥0.8): {stats['confidence_distribution']['high']}")
    print(f"    Medium (0.5-0.8): {stats['confidence_distribution']['medium']}")
    print(f"    Low (<0.5): {stats['confidence_distribution']['low']}")

    if args.detailed:
        techniques = analyzer.db.get_all_techniques()
        print(f"\n[*] All Detected Techniques ({len(techniques)}):")
        for tech in techniques[:20]:  # Show first 20
            print(f"  {tech.technique_id}: {tech.technique_name}")
            print(f"    Confidence: {tech.confidence:.2f} | Detections: {tech.detection_count}")
            print(f"    Evidence: {len(tech.evidence)}")

    analyzer.close()


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="MITRE Coverage Analysis CLI for Rowanholt",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Initialize coverage analysis
  %(prog)s init CASE-001 /output/CASE-001

  # Analyze single artifact
  %(prog)s analyze CASE-001 /output/CASE-001 powershell_history /evidence/ps.txt \\
      --context "Invoke-Mimikatz"

  # Batch analysis from file
  %(prog)s batch CASE-001 /output/CASE-001 artifacts.csv

  # Generate report
  %(prog)s report CASE-001 /output/CASE-001 --detailed

  # Generate standalone dashboard
  %(prog)s dashboard CASE-001 /output/CASE-001

  # Export all formats
  %(prog)s export CASE-001 /output/CASE-001 --format json,csv,html,splunk,elastic

  # Show statistics
  %(prog)s stats CASE-001 /output/CASE-001
        """,
    )

    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Init command
    init_parser = subparsers.add_parser("init", help="Initialize coverage analysis")
    init_parser.add_argument("case_id", help="Case identifier")
    init_parser.add_argument("output_dir", help="Output directory")

    # Analyze command
    analyze_parser = subparsers.add_parser("analyze", help="Analyze single artifact")
    analyze_parser.add_argument("case_id", help="Case identifier")
    analyze_parser.add_argument("output_dir", help="Output directory")
    analyze_parser.add_argument("artifact_type", help="Artifact type")
    analyze_parser.add_argument("artifact_path", help="Path to artifact")
    analyze_parser.add_argument("-c", "--context", help="Context (command line, content, etc.)")
    analyze_parser.add_argument("-d", "--data", help="Artifact data as JSON string")

    # Batch command
    batch_parser = subparsers.add_parser("batch", help="Batch analyze from file list")
    batch_parser.add_argument("case_id", help="Case identifier")
    batch_parser.add_argument("output_dir", help="Output directory")
    batch_parser.add_argument(
        "artifact_list", help="File with artifact list (CSV: type,path,context)"
    )

    # Report command
    report_parser = subparsers.add_parser("report", help="Generate coverage report")
    report_parser.add_argument("case_id", help="Case identifier")
    report_parser.add_argument("output_dir", help="Output directory")
    report_parser.add_argument("--detailed", action="store_true", help="Show detailed report")

    # Dashboard command
    dashboard_parser = subparsers.add_parser("dashboard", help="Generate standalone dashboard")
    dashboard_parser.add_argument("case_id", help="Case identifier")
    dashboard_parser.add_argument("output_dir", help="Output directory")
    dashboard_parser.add_argument("-o", "--output", help="Output HTML file path")

    # Export command
    export_parser = subparsers.add_parser("export", help="Export coverage data")
    export_parser.add_argument("case_id", help="Case identifier")
    export_parser.add_argument("output_dir", help="Output directory")
    export_parser.add_argument(
        "-f",
        "--format",
        default="json,csv,html",
        help="Export formats (json,csv,html,splunk,elastic)",
    )
    export_parser.add_argument("-o", "--output", help="Output file/directory path")

    # Stats command
    stats_parser = subparsers.add_parser("stats", help="Show coverage statistics")
    stats_parser.add_argument("case_id", help="Case identifier")
    stats_parser.add_argument("output_dir", help="Output directory")
    stats_parser.add_argument("--detailed", action="store_true", help="Show detailed statistics")

    args = parser.parse_args()

    # Setup logging
    setup_logging(args.verbose)

    # Execute command
    if args.command == "init":
        cmd_init(args)
    elif args.command == "analyze":
        cmd_analyze(args)
    elif args.command == "batch":
        cmd_batch(args)
    elif args.command == "report":
        cmd_report(args)
    elif args.command == "dashboard":
        cmd_dashboard(args)
    elif args.command == "export":
        cmd_export(args)
    elif args.command == "stats":
        cmd_stats(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()

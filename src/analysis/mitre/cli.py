#!/usr/bin/env python3
"""
MITRE ATT&CK CLI Tools

Command-line interface for MITRE ATT&CK operations.

Usage:
    python -m analysis.mitre.cli update
    python -m analysis.mitre.cli map powershell_history --context "invoke-mimikatz"
    python -m analysis.mitre.cli dashboard --input artifacts.json --output /tmp/dashboards
    python -m analysis.mitre.cli info T1059.001
    python -m analysis.mitre.cli stats

Author: Rowanholt DF Acceleration Suite
Version: 2.1.0
"""

import argparse
import json
import sys
import logging
from pathlib import Path
from typing import Optional

from .attck_updater import MitreAttackUpdater
from .technique_mapper import TechniqueMapper
from .dashboard_generator import MitreDashboardGenerator


def setup_logging(verbose: bool = False):
    """Setup logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def cmd_update(args):
    """Update ATT&CK framework data."""
    print("[*] Updating MITRE ATT&CK framework data...")

    updater = MitreAttackUpdater()

    # Update cache
    success = updater.update_local_cache(domain=args.domain, force=args.force)

    if success:
        print(f"[+] Successfully updated ATT&CK {args.domain} data")

        # Load and display version info
        data = updater.load_cached_data(domain=args.domain)
        if data:
            print(f"[+] Version: {data.get('version', 'unknown')}")
            print(f"[+] Techniques: {len(data.get('techniques', {}))}")
            print(f"[+] Tactics: {len(data.get('tactics', {}))}")
            print(f"[+] Groups: {len(data.get('groups', {}))}")
            print(f"[+] Software: {len(data.get('software', {}))}")

            # Show recent changes if available
            if data.get("changelog"):
                print("\n[*] Recent changes:")
                for change in data["changelog"][:5]:  # Show last 5
                    print(f"  - {change}")
    else:
        print("[-] Failed to update ATT&CK data", file=sys.stderr)
        sys.exit(1)


def cmd_map(args):
    """Map artifact to techniques."""
    print(f"[*] Mapping artifact type: {args.artifact_type}")

    mapper = TechniqueMapper()

    # Prepare artifact data
    artifact_data = None
    if args.data:
        try:
            artifact_data = json.loads(args.data)
        except json.JSONDecodeError:
            print(f"[-] Invalid JSON in --data: {args.data}", file=sys.stderr)
            sys.exit(1)

    # Map artifact to techniques
    techniques = mapper.map_artifact_to_techniques(
        artifact_type=args.artifact_type, artifact_data=artifact_data, context=args.context
    )

    if not techniques:
        print("[-] No techniques mapped for this artifact")
        sys.exit(0)

    print(f"[+] Found {len(techniques)} technique(s):\n")

    # Display results
    for tech in techniques:
        print(f"  {tech['id']}: {tech['name']}")
        print(f"    Confidence: {tech['confidence']:.2f}")
        print(f"    Tactics: {', '.join(tech['tactics'])}")

        # Show confidence factors
        factors = tech.get("confidence_factors", {})
        if any(v > 0 for v in factors.values() if isinstance(v, (int, float))):
            print(f"    Confidence factors:")
            for factor, value in factors.items():
                if isinstance(value, (int, float)) and value > 0:
                    print(f"      - {factor}: {value:.2f}")
        print()

    # Export if requested
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w") as f:
            json.dump(techniques, f, indent=2)

        print(f"[+] Results exported to {output_path}")


def cmd_dashboard(args):
    """Generate MITRE coverage dashboards."""
    print("[*] Generating MITRE ATT&CK coverage dashboards...")

    # Load technique mappings
    if args.input:
        input_path = Path(args.input)
        if not input_path.exists():
            print(f"[-] Input file not found: {input_path}", file=sys.stderr)
            sys.exit(1)

        with open(input_path, "r") as f:
            technique_mappings = json.load(f)
    else:
        print(
            "[-] No input file specified. Use --input to provide technique mappings.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Determine formats
    formats = args.formats.split(",") if args.formats else None

    # Generate dashboards
    generator = MitreDashboardGenerator()
    result = generator.save_dashboards(
        technique_mappings=technique_mappings, output_dir=args.output, formats=formats
    )

    print(f"\n[+] Dashboards generated in: {result['output_dir']}")

    if "splunk" in result:
        print(f"  - Splunk: {result['splunk']}")
    if "elastic" in result:
        print(f"  - Kibana: {result['elastic']}")
    if "navigator" in result:
        print(f"  - Navigator: {result['navigator']}")
    if "statistics" in result:
        print(f"  - Statistics: {result['statistics']}")


def cmd_info(args):
    """Display technique information."""
    print(f"[*] Looking up technique: {args.technique_id}")

    updater = MitreAttackUpdater()
    data = updater.load_cached_data(domain=args.domain)

    if not data:
        print("[-] No ATT&CK data found. Run 'update' command first.", file=sys.stderr)
        sys.exit(1)

    technique = data.get("techniques", {}).get(args.technique_id)

    if not technique:
        print(f"[-] Technique {args.technique_id} not found", file=sys.stderr)
        sys.exit(1)

    # Display technique details
    print(f"\n[+] {technique['id']}: {technique['name']}")
    print(f"\nDescription:")
    print(f"  {technique.get('description', 'No description available')}")

    print(f"\nTactics:")
    for tactic in technique.get("tactics", []):
        print(f"  - {tactic}")

    if technique.get("platforms"):
        print(f"\nPlatforms:")
        for platform in technique["platforms"]:
            print(f"  - {platform}")

    if technique.get("detection"):
        print(f"\nDetection:")
        print(f"  {technique['detection']}")

    if technique.get("url"):
        print(f"\nURL: {technique['url']}")

    # Export if requested
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w") as f:
            json.dump(technique, f, indent=2)

        print(f"\n[+] Details exported to {output_path}")


def cmd_stats(args):
    """Display ATT&CK statistics."""
    print("[*] ATT&CK Framework Statistics\n")

    updater = MitreAttackUpdater()
    data = updater.load_cached_data(domain=args.domain)

    if not data:
        print("[-] No ATT&CK data found. Run 'update' command first.", file=sys.stderr)
        sys.exit(1)

    print(f"Domain: {args.domain}")
    print(f"Version: {data.get('version', 'unknown')}")
    print(f"Last updated: {data.get('last_updated', 'unknown')}")
    print()

    # Count statistics
    techniques = data.get("techniques", {})
    tactics = data.get("tactics", {})
    groups = data.get("groups", {})
    software = data.get("software", {})
    mitigations = data.get("mitigations", {})

    print(f"Techniques: {len(techniques)}")
    print(f"Tactics: {len(tactics)}")
    print(f"Groups: {len(groups)}")
    print(f"Software: {len(software)}")
    print(f"Mitigations: {len(mitigations)}")
    print()

    # Technique breakdown by tactic
    if args.detailed:
        print("Techniques by Tactic:")
        tactic_counts = {}
        for technique in techniques.values():
            for tactic in technique.get("tactics", []):
                tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1

        for tactic, count in sorted(tactic_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"  {tactic}: {count}")
        print()

        # Platform breakdown
        print("Techniques by Platform:")
        platform_counts = {}
        for technique in techniques.values():
            for platform in technique.get("platforms", []):
                platform_counts[platform] = platform_counts.get(platform, 0) + 1

        for platform, count in sorted(platform_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"  {platform}: {count}")

    # Mapper statistics
    mapper = TechniqueMapper(updater)
    mapper_stats = mapper.get_statistics()

    print(f"\nTechnique Mapper Statistics:")
    print(f"Artifact types: {mapper_stats['artifact_types']}")
    print(f"Total mappings: {mapper_stats['total_mappings']}")
    print(f"Context rules: {mapper_stats['context_rules']}")


def cmd_list_artifacts(args):
    """List available artifact types."""
    print("[*] Available Artifact Types\n")

    mapper = TechniqueMapper()

    artifact_types = sorted(mapper.ARTIFACT_MAPPINGS.keys())

    print(f"Total artifact types: {len(artifact_types)}\n")

    for artifact_type in artifact_types:
        techniques = mapper.get_techniques_by_artifact_type(artifact_type)
        print(f"  {artifact_type}")
        print(f"    Mapped techniques: {len(techniques)}")
        if args.detailed:
            for tech_id in techniques:
                print(f"      - {tech_id}")
        print()


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="MITRE ATT&CK CLI Tools for Rowanholt",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Update ATT&CK data
  %(prog)s update

  # Map PowerShell artifact
  %(prog)s map powershell_history --context "invoke-mimikatz"

  # Map with additional data
  %(prog)s map prefetch --data '{"filename":"mimikatz.exe"}'

  # Generate dashboards
  %(prog)s dashboard --input mappings.json --output /tmp/dashboards

  # Get technique info
  %(prog)s info T1059.001

  # Show statistics
  %(prog)s stats --detailed
        """,
    )

    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Update command
    update_parser = subparsers.add_parser("update", help="Update ATT&CK framework data")
    update_parser.add_argument(
        "-d",
        "--domain",
        default="enterprise",
        choices=["enterprise", "mobile", "ics"],
        help="ATT&CK domain to update (default: enterprise)",
    )
    update_parser.add_argument(
        "-f", "--force", action="store_true", help="Force update even if cache is fresh"
    )

    # Map command
    map_parser = subparsers.add_parser("map", help="Map artifact to techniques")
    map_parser.add_argument("artifact_type", help="Type of artifact (e.g., powershell_history)")
    map_parser.add_argument("-c", "--context", help="Context string to analyze")
    map_parser.add_argument("-d", "--data", help="Artifact data as JSON string")
    map_parser.add_argument("-o", "--output", help="Output file for results (JSON)")

    # Dashboard command
    dashboard_parser = subparsers.add_parser("dashboard", help="Generate coverage dashboards")
    dashboard_parser.add_argument(
        "-i", "--input", required=True, help="Input file with technique mappings (JSON)"
    )
    dashboard_parser.add_argument(
        "-o",
        "--output",
        default="/tmp/rowanholt/dashboards",
        help="Output directory for dashboards",
    )
    dashboard_parser.add_argument(
        "-f", "--formats", help="Comma-separated formats (splunk,elastic,navigator)"
    )

    # Info command
    info_parser = subparsers.add_parser("info", help="Display technique information")
    info_parser.add_argument("technique_id", help="Technique ID (e.g., T1059.001)")
    info_parser.add_argument(
        "-d",
        "--domain",
        default="enterprise",
        choices=["enterprise", "mobile", "ics"],
        help="ATT&CK domain (default: enterprise)",
    )
    info_parser.add_argument("-o", "--output", help="Output file for details (JSON)")

    # Stats command
    stats_parser = subparsers.add_parser("stats", help="Display ATT&CK statistics")
    stats_parser.add_argument(
        "-d",
        "--domain",
        default="enterprise",
        choices=["enterprise", "mobile", "ics"],
        help="ATT&CK domain (default: enterprise)",
    )
    stats_parser.add_argument("--detailed", action="store_true", help="Show detailed statistics")

    # List artifacts command
    list_parser = subparsers.add_parser("list-artifacts", help="List available artifact types")
    list_parser.add_argument(
        "--detailed", action="store_true", help="Show mapped techniques for each artifact type"
    )

    args = parser.parse_args()

    # Setup logging
    setup_logging(args.verbose)

    # Execute command
    if args.command == "update":
        cmd_update(args)
    elif args.command == "map":
        cmd_map(args)
    elif args.command == "dashboard":
        cmd_dashboard(args)
    elif args.command == "info":
        cmd_info(args)
    elif args.command == "stats":
        cmd_stats(args)
    elif args.command == "list-artifacts":
        cmd_list_artifacts(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()

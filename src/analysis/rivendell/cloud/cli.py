#!/usr/bin/env python3
"""
Unified Cloud Forensics CLI

Command-line interface for cloud forensics operations across AWS, Azure, and GCP.

Author: Rivendell DF Acceleration Suite
Version: 2.1.0
"""

import argparse
import json
import os
import sys
from datetime import datetime, timedelta
from typing import Optional

from .aws import AWSForensics, CloudTrailAnalyzer, S3Forensics
from .azure import AzureForensics, ActivityLogAnalyzer
from .gcp import GCPForensics, CloudLoggingAnalyzer
from .base import CloudForensicsException
from .k8s import analyse_audit_log


def load_credentials(provider: str, cred_file: Optional[str] = None) -> dict:
    """
    Load cloud provider credentials from file or environment.

    Args:
        provider: Cloud provider name (aws, azure, gcp)
        cred_file: Optional credentials file path

    Returns:
        Credentials dictionary
    """
    if cred_file and os.path.exists(cred_file):
        with open(cred_file, "r") as f:
            return json.load(f)

    # Try environment variables
    if provider == "aws":
        return {
            "access_key": os.getenv("AWS_ACCESS_KEY_ID"),
            "secret_key": os.getenv("AWS_SECRET_ACCESS_KEY"),
            "region": os.getenv("AWS_REGION", "us-east-1"),
            "session_token": os.getenv("AWS_SESSION_TOKEN"),
        }
    elif provider == "azure":
        return {
            "tenant_id": os.getenv("AZURE_TENANT_ID"),
            "client_id": os.getenv("AZURE_CLIENT_ID"),
            "client_secret": os.getenv("AZURE_CLIENT_SECRET"),
            "subscription_id": os.getenv("AZURE_SUBSCRIPTION_ID"),
        }
    elif provider == "gcp":
        return {
            "project_id": os.getenv("GCP_PROJECT_ID"),
            "service_account_file": os.getenv("GOOGLE_APPLICATION_CREDENTIALS"),
        }

    return {}


def list_instances_command(args):
    """List cloud instances."""
    credentials = load_credentials(args.provider, args.credentials)

    try:
        if args.provider == "aws":
            client = AWSForensics(credentials)
            client.authenticate()
            instances = client.list_instances(region=args.region)

        elif args.provider == "azure":
            client = AzureForensics(credentials)
            client.authenticate()
            instances = client.list_instances(resource_group=args.resource_group)

        elif args.provider == "gcp":
            client = GCPForensics(credentials)
            client.authenticate()
            instances = client.list_instances(zone=args.zone)

        else:
            print(f"Unknown provider: {args.provider}")
            return 1

        # Output
        if args.output:
            with open(args.output, "w") as f:
                json.dump(instances, f, indent=2, default=str)
            print(f"Instances saved to {args.output}")
        else:
            print(f"\nFound {len(instances)} instances:")
            for instance in instances:
                print(
                    f"  - {instance['name']} ({instance['id']}) - {instance.get('state', instance.get('status', 'N/A'))}"
                )

        return 0

    except CloudForensicsException as e:
        print(f"Error: {e}")
        return 1


def acquire_disk_command(args):
    """Acquire disk snapshots."""
    credentials = load_credentials(args.provider, args.credentials)
    output_dir = args.output or "."

    os.makedirs(output_dir, exist_ok=True)

    try:
        if args.provider == "aws":
            client = AWSForensics(credentials)
            client.authenticate()
            result = client.acquire_disk_image(args.instance_id, output_dir, wait=args.wait)

        elif args.provider == "azure":
            client = AzureForensics(credentials)
            client.authenticate()
            result = client.acquire_disk_image(
                args.instance_id, output_dir, resource_group=args.resource_group
            )

        elif args.provider == "gcp":
            client = GCPForensics(credentials)
            client.authenticate()
            result = client.acquire_disk_image(args.instance_id, output_dir, zone=args.zone)

        else:
            print(f"Unknown provider: {args.provider}")
            return 1

        print(f"\nDisk acquisition complete:")
        print(
            f"  Instance: {result.get('instance_id', result.get('vm_name', result.get('instance_name')))}"
        )
        print(f"  Snapshots created: {len(result['snapshots'])}")
        for snapshot in result["snapshots"]:
            print(f"    - {snapshot.get('snapshot_id', snapshot.get('snapshot_name'))}")

        return 0

    except CloudForensicsException as e:
        print(f"Error: {e}")
        return 1


def acquire_logs_command(args):
    """Acquire cloud audit logs."""
    credentials = load_credentials(args.provider, args.credentials)
    output_dir = args.output or "."

    os.makedirs(output_dir, exist_ok=True)

    # Parse time range
    if args.days:
        end_time = datetime.now()
        start_time = end_time - timedelta(days=args.days)
    else:
        start_time = (
            datetime.fromisoformat(args.start_time)
            if args.start_time
            else datetime.now() - timedelta(days=1)
        )
        end_time = datetime.fromisoformat(args.end_time) if args.end_time else datetime.now()

    try:
        if args.provider == "aws":
            session = AWSForensics(credentials).session
            analyzer = CloudTrailAnalyzer(session)
            output_files = analyzer.acquire_logs(start_time, end_time, output_dir)

        elif args.provider == "azure":
            client = AzureForensics(credentials)
            client.authenticate()
            analyzer = ActivityLogAnalyzer(client.credential, client.subscription_id)
            output_files = analyzer.acquire_logs(start_time, end_time, output_dir)

        elif args.provider == "gcp":
            project_id = credentials.get("project_id")
            analyzer = CloudLoggingAnalyzer(project_id)
            output_files = analyzer.acquire_logs(start_time, end_time, output_dir)

        else:
            print(f"Unknown provider: {args.provider}")
            return 1

        print(f"\nLog acquisition complete:")
        print(f"  Time range: {start_time.isoformat()} to {end_time.isoformat()}")
        print(f"  Output files:")
        for file in output_files:
            print(f"    - {file}")

        # Analyze if requested
        if args.analyze and output_files:
            print(f"\nAnalyzing logs...")
            analyze_logs_command_impl(args.provider, credentials, output_files[0], output_dir)

        return 0

    except CloudForensicsException as e:
        print(f"Error: {e}")
        return 1


def analyze_logs_command(args):
    """Analyze cloud audit logs."""
    if args.provider == "k8s":
        summary = analyse_audit_log(args.log_file, args.output or os.path.dirname(os.path.abspath(args.log_file)))
        print(f"\nKubernetes audit log: {summary['total_events']} events, {summary['flagged_events']} flagged")
        for technique, flagged in sorted(summary["techniques"].items()):
            print(f"    - {technique}: {len(flagged)} events")
        return 0
    credentials = load_credentials(args.provider, args.credentials)
    output_dir = args.output or os.path.dirname(args.log_file)

    return analyze_logs_command_impl(args.provider, credentials, args.log_file, output_dir)


def analyze_logs_command_impl(
    provider: str, credentials: dict, log_file: str, output_dir: str
) -> int:
    """Implementation of log analysis."""
    try:
        if provider == "aws":
            analyzer = CloudTrailAnalyzer()
            findings = analyzer.analyze_logs(log_file)
            report_file = os.path.join(output_dir, "cloudtrail_analysis.json")
            analyzer.generate_report(findings, report_file)

        elif provider == "azure":
            # Get required credentials
            client = AzureForensics(credentials)
            client.authenticate()
            analyzer = ActivityLogAnalyzer(client.credential, client.subscription_id)
            findings = analyzer.analyze_logs(log_file)
            report_file = os.path.join(output_dir, "activity_log_analysis.json")
            analyzer.generate_report(findings, report_file)

        elif provider == "gcp":
            project_id = credentials.get("project_id")
            analyzer = CloudLoggingAnalyzer(project_id)
            findings = analyzer.analyze_logs(log_file)
            report_file = os.path.join(output_dir, "cloud_logging_analysis.json")
            analyzer.generate_report(findings, report_file)

        else:
            print(f"Unknown provider: {provider}")
            return 1

        print(f"\nLog analysis complete:")
        print(f"  Total events: {findings['statistics']['total_events']}")
        print(
            f"  Suspicious events: {len(findings.get('suspicious_events', findings.get('suspicious_operations', findings.get('suspicious_methods', []))))}"
        )
        print(f"  Report saved to: {report_file}")

        # Show MITRE ATT&CK mapping summary
        mitre_map = analyzer.map_to_mitre(findings)
        if mitre_map:
            print(f"\n  MITRE ATT&CK Techniques Detected:")
            for technique, events in mitre_map.items():
                print(f"    - {technique}: {len(events)} events")

        return 0

    except Exception as e:
        print(f"Error: {e}")
        return 1


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Rivendell Cloud Forensics CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # List AWS instances
  %(prog)s aws list --credentials aws_creds.json

  # Acquire Azure VM disk snapshot
  %(prog)s azure acquire-disk --instance-id myvm --resource-group mygroup --output ./output

  # Acquire and analyze CloudTrail logs
  %(prog)s aws acquire-logs --days 7 --analyze --output ./logs

  # Analyze existing logs
  %(prog)s aws analyze-logs --log-file cloudtrail_logs.json

  # Analyze a Kubernetes API server audit log (EKS, AKS, GKE or self-managed)
  %(prog)s k8s analyze-logs --log-file audit.log --output ./case
        """,
    )

    parser.add_argument("provider", choices=["aws", "azure", "gcp", "k8s"],
                        help="Cloud provider, or k8s for an exported Kubernetes audit log")

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # List instances command
    list_parser = subparsers.add_parser("list", help="List cloud instances")
    list_parser.add_argument("--credentials", "-c", help="Credentials file path")
    list_parser.add_argument("--region", help="AWS region or Azure location")
    list_parser.add_argument("--resource-group", help="Azure resource group")
    list_parser.add_argument("--zone", help="GCP zone")
    list_parser.add_argument("--output", "-o", help="Output file path")

    # Acquire disk command
    disk_parser = subparsers.add_parser("acquire-disk", help="Acquire disk snapshots")
    disk_parser.add_argument("--instance-id", "-i", required=True, help="Instance ID/name")
    disk_parser.add_argument("--credentials", "-c", help="Credentials file path")
    disk_parser.add_argument("--region", help="AWS region")
    disk_parser.add_argument("--resource-group", help="Azure resource group")
    disk_parser.add_argument("--zone", help="GCP zone")
    disk_parser.add_argument("--output", "-o", help="Output directory")
    disk_parser.add_argument("--wait", action="store_true", help="Wait for snapshots to complete")

    # Acquire logs command
    logs_parser = subparsers.add_parser("acquire-logs", help="Acquire audit logs")
    logs_parser.add_argument("--credentials", "-c", help="Credentials file path")
    logs_parser.add_argument("--days", type=int, help="Number of days to retrieve (from now)")
    logs_parser.add_argument("--start-time", help="Start time (ISO format)")
    logs_parser.add_argument("--end-time", help="End time (ISO format)")
    logs_parser.add_argument("--output", "-o", help="Output directory")
    logs_parser.add_argument(
        "--analyze", action="store_true", help="Analyze logs after acquisition"
    )

    # Analyze logs command
    analyze_parser = subparsers.add_parser("analyze-logs", help="Analyze audit logs")
    analyze_parser.add_argument("--log-file", "-f", required=True, help="Log file to analyze")
    analyze_parser.add_argument("--credentials", "-c", help="Credentials file path")
    analyze_parser.add_argument("--output", "-o", help="Output directory")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    # Route to command handler
    if args.command == "list":
        return list_instances_command(args)
    elif args.command == "acquire-disk":
        return acquire_disk_command(args)
    elif args.command == "acquire-logs":
        return acquire_logs_command(args)
    elif args.command == "analyze-logs":
        return analyze_logs_command(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
Dernvale Mordor Dataset Manager

CLI for managing OTRF Security Datasets (Mordor datasets) for forensic analysis
and threat hunting.

Usage:
    dernvale-mordor list [--platform PLATFORM] [--tactic TACTIC] [--technique TECHNIQUE] [--search TEXT]
    dernvale-mordor download <dataset_id> [--output DIR]
    dernvale-mordor info <dataset_id>
    dernvale-mordor local [--status STATUS]
    dernvale-mordor delete <dataset_id> [--force]
    dernvale-mordor verify <dataset_id>
    dernvale-mordor refresh [--force]
    dernvale-mordor stats
"""

import argparse
import sys
from typing import Optional

# Add project root to path for imports
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.mordor import MordorCatalog, MordorDownloader, MordorStorage


def format_size(size_bytes: Optional[int]) -> str:
    """Format bytes to human-readable string."""
    if not size_bytes:
        return "N/A"

    units = ["B", "KB", "MB", "GB", "TB"]
    unit_index = 0
    size = float(size_bytes)

    while size >= 1024 and unit_index < len(units) - 1:
        size /= 1024
        unit_index += 1

    return f"{size:.1f} {units[unit_index]}"


def print_table(headers: list, rows: list, col_widths: Optional[list] = None):
    """Print a simple text table."""
    if not col_widths:
        col_widths = [max(len(str(row[i])) for row in [headers] + rows) + 2
                     for i in range(len(headers))]

    # Header
    header_line = "  ".join(str(h).ljust(w) for h, w in zip(headers, col_widths))
    print(header_line)
    print("-" * len(header_line))

    # Rows
    for row in rows:
        row_line = "  ".join(str(c)[:w].ljust(w) for c, w in zip(row, col_widths))
        print(row_line)


def cmd_list(args):
    """List available datasets from OTRF catalog."""
    catalog = MordorCatalog()

    print("[*] Fetching Mordor dataset catalog...")
    datasets = catalog.list_datasets(
        platform=args.platform,
        tactic=args.tactic,
        technique=args.technique,
        search=args.search,
        limit=args.limit,
    )

    if not datasets:
        print("\nNo datasets found matching your criteria.")
        return 0

    # Format table
    headers = ["ID", "Title", "Platform", "Tactics", "Techniques"]
    col_widths = [20, 45, 10, 20, 15]
    rows = []

    for ds in datasets:
        tactics_str = ", ".join(ds.tactics[:2])
        if len(ds.tactics) > 2:
            tactics_str += f" +{len(ds.tactics) - 2}"

        techs_str = ", ".join(ds.techniques[:2])
        if len(ds.techniques) > 2:
            techs_str += f" +{len(ds.techniques) - 2}"

        title = ds.title[:42] + "..." if len(ds.title) > 45 else ds.title

        rows.append([ds.dataset_id, title, ds.platform, tactics_str, techs_str])

    print()
    print_table(headers, rows, col_widths)
    print(f"\nTotal: {len(datasets)} datasets")

    stats = catalog.get_statistics()
    print(f"\nCatalog last updated: {stats.get('last_updated', 'Never')}")

    return 0


def cmd_download(args):
    """Download a specific dataset."""
    catalog = MordorCatalog()
    downloader = MordorDownloader(catalog)
    storage = MordorStorage(args.output)

    # Check if already downloaded
    if storage.dataset_exists(args.dataset_id):
        print(f"[!] Dataset {args.dataset_id} already downloaded at:")
        print(f"    {storage.get_dataset_path(args.dataset_id)}")
        if not args.force:
            confirm = input("\nRe-download? [y/N]: ")
            if confirm.lower() != "y":
                print("Cancelled.")
                return 0

    print(f"[*] Downloading dataset: {args.dataset_id}")

    # Progress tracking
    last_progress = [0]

    def progress_callback(current, total):
        pct = int((current / total) * 100) if total > 0 else 0
        if pct >= last_progress[0] + 10:
            print(f"    Progress: {pct}%")
            last_progress[0] = pct

    result = downloader.download(
        args.dataset_id,
        output_dir=str(storage.get_dataset_path(args.dataset_id)),
        progress_callback=progress_callback,
    )

    if result.success:
        print(f"\n[+] Download complete!")
        print(f"    Files: {len(result.files)}")
        print(f"    Size: {format_size(result.total_size)}")
        print(f"    Path: {result.local_path}")
        return 0
    else:
        print(f"\n[ERROR] Download failed: {result.error}")
        return 1


def cmd_info(args):
    """Show detailed information about a dataset."""
    catalog = MordorCatalog()
    storage = MordorStorage()

    dataset = catalog.get_dataset(args.dataset_id)

    if not dataset:
        print(f"[ERROR] Dataset not found: {args.dataset_id}")
        return 1

    # Check local status
    local_info = storage.get_dataset_info(args.dataset_id)
    status = "Downloaded" if local_info else "Available"

    print()
    print("=" * 70)
    print(f"Dataset: {dataset.title}")
    print("=" * 70)
    print(f"ID:          {dataset.dataset_id}")
    print(f"Platform:    {dataset.platform}")
    print(f"Type:        {dataset.dataset_type}")
    print(f"Status:      {status}")
    if local_info:
        print(f"Local Path:  {local_info.get('local_path')}")
        print(f"Downloaded:  {local_info.get('downloaded_at', 'Unknown')}")

    if dataset.description:
        print(f"\nDescription:")
        # Word wrap description
        desc = dataset.description
        while len(desc) > 65:
            idx = desc[:65].rfind(" ")
            if idx == -1:
                idx = 65
            print(f"  {desc[:idx]}")
            desc = desc[idx:].strip()
        if desc:
            print(f"  {desc}")

    if dataset.attack_mappings:
        print(f"\nMITRE ATT&CK Mapping:")
        for mapping in dataset.attack_mappings:
            tactics = ", ".join(mapping.tactics) if mapping.tactics else "N/A"
            print(f"  - {mapping.technique}: {tactics}")

    if dataset.files:
        print(f"\nFiles ({len(dataset.files)}):")
        for f in dataset.files:
            filename = f.link.split("/")[-1] if f.link else "unknown"
            print(f"  - [{f.type}] {filename}")

    if dataset.simulation:
        print(f"\nSimulation:")
        if dataset.simulation.tools:
            tools = ", ".join(t.name for t in dataset.simulation.tools)
            print(f"  Tools: {tools}")
        if dataset.simulation.permissions_required:
            perms = ", ".join(dataset.simulation.permissions_required)
            print(f"  Permissions: {perms}")

    if dataset.tags:
        print(f"\nTags: {', '.join(dataset.tags)}")

    if dataset.references:
        print(f"\nReferences:")
        for ref in dataset.references[:5]:
            print(f"  - {ref}")
        if len(dataset.references) > 5:
            print(f"  ... and {len(dataset.references) - 5} more")

    print()
    return 0


def cmd_local(args):
    """List locally downloaded datasets."""
    storage = MordorStorage()
    datasets = storage.list_local_datasets(status=args.status)

    if not datasets:
        print("\nNo datasets downloaded locally.")
        print(f"Storage path: {storage.storage_dir}")
        return 0

    # Format table
    headers = ["ID", "Title", "Platform", "Size", "Downloaded"]
    col_widths = [20, 40, 10, 12, 20]
    rows = []

    for ds in datasets:
        title = ds["title"]
        if len(title) > 37:
            title = title[:37] + "..."

        downloaded = ds.get("downloaded_at", "N/A")
        if downloaded and len(downloaded) > 20:
            downloaded = downloaded[:19]

        rows.append([
            ds["dataset_id"],
            title,
            ds["platform"],
            format_size(ds.get("total_size")),
            downloaded,
        ])

    print()
    print_table(headers, rows, col_widths)
    print(f"\nTotal: {len(datasets)} datasets")

    stats = storage.get_storage_stats()
    print(f"Total size: {stats['total_size_human']}")
    print(f"Storage path: {stats['storage_path']}")

    return 0


def cmd_delete(args):
    """Delete a locally downloaded dataset."""
    storage = MordorStorage()

    if not storage.dataset_exists(args.dataset_id):
        print(f"[ERROR] Dataset not found locally: {args.dataset_id}")
        return 1

    if not args.force:
        confirm = input(f"Delete dataset {args.dataset_id}? [y/N]: ")
        if confirm.lower() != "y":
            print("Cancelled.")
            return 0

    if storage.delete_dataset(args.dataset_id):
        print(f"[+] Dataset deleted: {args.dataset_id}")
        return 0
    else:
        print(f"[ERROR] Failed to delete dataset: {args.dataset_id}")
        return 1


def cmd_verify(args):
    """Verify integrity of a downloaded dataset."""
    storage = MordorStorage()

    if not storage.dataset_exists(args.dataset_id):
        print(f"[ERROR] Dataset not found locally: {args.dataset_id}")
        return 1

    print(f"[*] Verifying dataset: {args.dataset_id}")
    result = storage.verify_dataset(args.dataset_id)

    if result.valid:
        print(f"\n[+] Dataset verified successfully!")
        print(f"    Files checked: {result.files_checked}/{result.total_files}")
        return 0
    else:
        print(f"\n[ERROR] Verification failed!")
        for error in result.errors:
            print(f"    - {error}")
        return 1


def cmd_refresh(args):
    """Refresh the dataset catalog from OTRF."""
    catalog = MordorCatalog()

    print("[*] Refreshing catalog from OTRF Security Datasets...")
    count = catalog.refresh(force=args.force)

    if count > 0:
        print(f"[+] Catalog refreshed: {count} datasets indexed")
        stats = catalog.get_statistics()
        print(f"\nPlatforms: {dict(stats.get('platforms', {}))}")
        print(f"Tactics: {len(stats.get('tactics', {}))} unique")
        return 0
    else:
        print("[!] No datasets found. Check your internet connection.")
        return 1


def cmd_stats(args):
    """Show storage and catalog statistics."""
    catalog = MordorCatalog()
    storage = MordorStorage()

    print("\n" + "=" * 50)
    print("  Mordor Dataset Statistics")
    print("=" * 50)

    # Catalog stats
    print("\nCatalog:")
    cat_stats = catalog.get_statistics()
    print(f"  Total datasets: {cat_stats.get('total', 0)}")
    print(f"  Last updated: {cat_stats.get('last_updated', 'Never')}")

    platforms = cat_stats.get('platforms', {})
    if platforms:
        print(f"  Platforms: {dict(platforms)}")

    # Storage stats
    print("\nLocal Storage:")
    stor_stats = storage.get_storage_stats()
    print(f"  Downloaded datasets: {stor_stats['total_datasets']}")
    print(f"  Total size: {stor_stats['total_size_human']}")
    print(f"  Total files: {stor_stats['total_files']}")
    print(f"  Storage path: {stor_stats['storage_path']}")

    if stor_stats.get('platforms'):
        print(f"  Platforms: {dict(stor_stats['platforms'])}")

    print()
    return 0


def main():
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        description="Dernvale Mordor Dataset Manager - Manage OTRF Security Datasets",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s list                           List all available datasets
  %(prog)s list --platform windows        List Windows datasets
  %(prog)s list --tactic execution        List datasets for execution tactic
  %(prog)s list --search "powershell"     Search for PowerShell-related datasets
  %(prog)s download SDWIN-190518182022    Download a specific dataset
  %(prog)s info SDWIN-190518182022        Show dataset details
  %(prog)s local                          List downloaded datasets
  %(prog)s verify SDWIN-190518182022      Verify dataset integrity
  %(prog)s delete SDWIN-190518182022      Delete a local dataset
  %(prog)s refresh                        Refresh catalog from OTRF
  %(prog)s stats                          Show statistics

For more information, visit: https://github.com/OTRF/Security-Datasets
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # list command
    list_parser = subparsers.add_parser("list", help="List available datasets")
    list_parser.add_argument(
        "--platform",
        choices=["windows", "linux", "aws"],
        help="Filter by platform",
    )
    list_parser.add_argument("--tactic", help="Filter by MITRE tactic")
    list_parser.add_argument("--technique", help="Filter by MITRE technique ID (e.g., T1059.001)")
    list_parser.add_argument("--search", "-s", help="Search in title/description")
    list_parser.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Maximum number of results (default: 50)",
    )

    # download command
    dl_parser = subparsers.add_parser("download", help="Download a dataset")
    dl_parser.add_argument("dataset_id", help="Dataset ID (e.g., SDWIN-190518182022)")
    dl_parser.add_argument(
        "--output",
        "-o",
        help="Output directory (default: /tmp/dernvale/mordor)",
    )
    dl_parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Force re-download if already exists",
    )

    # info command
    info_parser = subparsers.add_parser("info", help="Show dataset details")
    info_parser.add_argument("dataset_id", help="Dataset ID")

    # local command
    local_parser = subparsers.add_parser("local", help="List local datasets")
    local_parser.add_argument(
        "--status",
        choices=["downloaded", "downloading", "failed"],
        help="Filter by status",
    )

    # delete command
    del_parser = subparsers.add_parser("delete", help="Delete local dataset")
    del_parser.add_argument("dataset_id", help="Dataset ID")
    del_parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Skip confirmation",
    )

    # verify command
    verify_parser = subparsers.add_parser("verify", help="Verify dataset integrity")
    verify_parser.add_argument("dataset_id", help="Dataset ID")

    # refresh command
    refresh_parser = subparsers.add_parser("refresh", help="Refresh catalog")
    refresh_parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Force refresh even if cache is fresh",
    )

    # stats command
    stats_parser = subparsers.add_parser("stats", help="Show statistics")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    # Route to command handler
    commands = {
        "list": cmd_list,
        "download": cmd_download,
        "info": cmd_info,
        "local": cmd_local,
        "delete": cmd_delete,
        "verify": cmd_verify,
        "refresh": cmd_refresh,
        "stats": cmd_stats,
    }

    try:
        return commands[args.command](args)
    except KeyboardInterrupt:
        print("\n\nCancelled by user.")
        return 130
    except Exception as e:
        print(f"\n[ERROR] {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())

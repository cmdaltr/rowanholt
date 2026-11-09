#!/usr/bin/env python3 -tt
"""
MITRE ATT&CK Navigator Configuration

Generates Navigator layer JSON from processed artefacts.
Primary method: Read techniques from mitre_techniques.txt file created during enrichment.
This avoids re-reading large JSON files and prevents OOM issues.

Author: Rowanholt DF Acceleration Suite
Version: 2.3.0
"""

import json
import os
import shutil
from datetime import datetime
from typing import List, Optional, Set

from rowanholt.post.mitre import attack_lookup
from rowanholt.post.mitre.layers import build_layer, layer_file, navigator_config
from rowanholt.post.mitre.enrichment import TECHNIQUES_FILE, get_techniques_from_file

LAYER_COLOUR = "#00acb4"
NAV_ASSETS_DIR = "/navigator/dist/assets"  # the Navigator serves from here, not its source folder


def collect_techniques_from_file(artefacts_directory: str) -> Set[str]:
    """
    Read MITRE technique IDs from the techniques file created during enrichment.

    This is much faster and more memory-efficient than re-reading all JSON files.

    Args:
        artefacts_directory: Path to artefacts directory (contains mitre_techniques.txt)

    Returns:
        Set of technique IDs found
    """
    # Try to find the techniques file in various locations
    possible_paths = [
        os.path.join(artefacts_directory, TECHNIQUES_FILE),
        os.path.join(os.path.dirname(artefacts_directory.rstrip('/')), TECHNIQUES_FILE),
        os.path.join(artefacts_directory, '..', TECHNIQUES_FILE),
    ]

    # Also check parent directories up to 3 levels
    current = artefacts_directory
    for _ in range(3):
        parent = os.path.dirname(current.rstrip('/'))
        if parent and parent != current:
            possible_paths.append(os.path.join(parent, TECHNIQUES_FILE))
            current = parent

    for filepath in possible_paths:
        if os.path.exists(filepath):
            try:
                with open(filepath, 'r') as f:
                    techniques = set(line.strip() for line in f if line.strip())
                if techniques:
                    print(f"     Read {len(techniques)} techniques from {filepath}")
                    return techniques
            except Exception as e:
                print(f"     Warning: Error reading {filepath}: {e}")

    return set()


def write_navigator_layer(case: str, techniques: List[str], output_directory: Optional[str] = None) -> bool:
    """
    Write the case's Navigator layers, one per ATT&CK domain its techniques belong to:
    <case>.json (Enterprise) and <case>.mobile.json (Mobile), and point the Navigator at them.

    Args:
        case: Case name
        techniques: List of technique IDs
        output_directory: Output directory for copy

    Returns:
        True if at least one layer was written
    """
    nav_assets_dir = NAV_ASSETS_DIR

    grouped = attack_lookup.by_domain(techniques)
    unknown = grouped.pop(None, [])
    if unknown:
        print(f"     Not in ATT&CK v{attack_lookup.version()}, left out of the layer: {', '.join(unknown)}")
    if not grouped:
        return False

    written = []
    for domain, ids in grouped.items():
        layer = build_layer(case, domain, {tid: (LAYER_COLOUR, "") for tid in ids},
                            legend=[{"label": "Evidence of", "color": LAYER_COLOUR}])
        name = layer_file(case, domain)
        final_path = f"{nav_assets_dir}/{name}"
        try:
            with open(final_path, "w") as f:
                json.dump(layer, f, indent=4)
        except Exception as e:
            print(f"     Error writing Navigator layer: {e}")
            continue
        written.append(name)
        print(f"     {attack_lookup.DOMAIN_NAMES[domain]} layer: {len(ids)} techniques")

        # Copy to output directory
        if output_directory:
            suffix = "_mobile" if domain == attack_lookup.MOBILE else ""
            nav_dest = os.path.join(output_directory, f"{case}{suffix}_navigator.json")
            try:
                shutil.copy2(final_path, nav_dest)
                print(f"     Navigator layer copied to: {nav_dest}")
            except Exception as e:
                print(f"     Warning: Could not copy Navigator JSON: {str(e)[:100]}")

    if not written:
        return False
    write_navigator_config(written, nav_assets_dir)
    return True


def write_navigator_config(layer_names: List[str], nav_assets_dir: str):
    """Write Navigator config.json: the pinned release's domains, opening on these layers."""
    with open(f"{nav_assets_dir}/config.json", "w") as f:
        json.dump(navigator_config([f"assets/{name}" for name in layer_names]), f, indent=2)


def configure_navigator(verbosity, case, splunk, elastic, usercred, pswdcred, output_directory=None):
    """
    Configure MITRE ATT&CK Navigator with techniques found in artefacts.

    Reads MITRE technique IDs from mitre_techniques.txt file created during enrichment.
    This avoids re-reading large JSON files and prevents OOM issues.
    No SIEM dependency - techniques are identified during artefact processing.

    Note: splunk, elastic, usercred, pswdcred parameters are kept for backward
    compatibility but are no longer used.
    """
    print(f" -> {datetime.now().isoformat().replace('T', ' ')} -> mapping artefacts to MITRE ATT&CK Navigator...")

    # Check if Navigator is installed (serves from dist folder)
    nav_assets_dir = NAV_ASSETS_DIR
    if not os.path.exists(nav_assets_dir):
        print(f" -> {datetime.now().isoformat().replace('T', ' ')} -> ATT&CK Navigator not installed - skipping")
        print(f"     (Navigator assets directory not found: {nav_assets_dir})")
        return ""

    foundtechniques = []

    # Read techniques from CASE-level mitre_techniques.txt file
    # (All modules now write to a single consolidated file at case level)
    if output_directory:
        all_techniques = set()

        # Check for case-level techniques file (alongside rowanholt_audit.log)
        case_level_path = os.path.join(output_directory, TECHNIQUES_FILE)
        if os.path.exists(case_level_path):
            try:
                with open(case_level_path, 'r') as f:
                    all_techniques = set(line.strip() for line in f if line.strip())
                if all_techniques:
                    print(f"     Read {len(all_techniques)} techniques from case-level file")
            except Exception as e:
                print(f"     Warning: Error reading {case_level_path}: {e}")
        else:
            # Fallback: Find artefacts/cooked directory and look for techniques file nearby
            artefacts_dirs = []
            for root, dirs, files in os.walk(output_directory):
                # Only match the 'cooked' directory itself, not subdirs like 'cooked/browsers'
                if os.path.basename(root) == "cooked" or os.path.basename(root) == "artefacts":
                    artefacts_dirs.append(root)
                    break

            if artefacts_dirs:
                print("     Reading techniques from enrichment output...")
                all_techniques = collect_techniques_from_file(artefacts_dirs[0])

        if all_techniques:
            foundtechniques = list(all_techniques)

    # Process found techniques
    if not foundtechniques:
        print("     No evidence of MITRE ATT&CK techniques could be identified.")
        return ""

    # Deduplicate and add parent techniques
    subtechniques = sorted(list(set(foundtechniques)))
    maintechniques = []

    for tech in subtechniques:
        if "." in tech:
            # Add parent technique
            maintechniques.append(tech.split(".")[0])
        maintechniques.append(tech)

    alltechniques = sorted(list(set(maintechniques)))

    print(f"     Evidence of {len(subtechniques)} MITRE ATT&CK techniques identified.")

    # Write Navigator layer
    if write_navigator_layer(case, alltechniques, output_directory):
        print(f"     ATT&CK Navigator built for '{case}'")
        return "-"
    else:
        print("     Failed to build ATT&CK Navigator layer")
        return ""

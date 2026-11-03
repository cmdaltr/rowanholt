#!/usr/bin/env python3 -tt
"""
MITRE ATT&CK Navigator Configuration

Generates Navigator layer JSON from processed artefacts.
Primary method: Read techniques from mitre_techniques.txt file created during enrichment.
This avoids re-reading large JSON files and prevents OOM issues.

Author: Dernvale DF Acceleration Suite
Version: 2.2.0
"""

import json
import os
import shutil
from datetime import datetime
from typing import List, Optional, Set

from dernvale.post.mitre.nav_attack import create_attack_navigator
from dernvale.post.mitre.enrichment import TECHNIQUES_FILE, get_techniques_from_file


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
    Write Navigator layer JSON file.

    Args:
        case: Case name
        techniques: List of technique IDs
        output_directory: Output directory for copy

    Returns:
        True if successful
    """
    # Navigator serves from /navigator/dist/assets, not the source folder
    nav_assets_dir = "/navigator/dist/assets"

    # Build techniques list as proper JSON objects
    technique_objects = []
    for technique in techniques:
        # Get technique entries from nav_attack (may return multiple for multi-tactic techniques)
        nav_list = []
        create_attack_navigator(nav_list, technique)

        # Parse each entry and add to technique_objects
        # nav_attack.py already replaces ±§§± with full JSON, entries end with '},\n        '
        for entry in nav_list:
            # Clean up the entry - remove trailing comma and whitespace
            entry = entry.strip().rstrip(',').strip()

            # Split on '},\n        {' to handle multi-tactic techniques
            # But first wrap in array brackets to make it valid JSON
            if entry.startswith('{') and '},\n        {' in entry:
                # Multiple technique objects in one entry
                json_array_str = '[' + entry + ']'
                # Clean up any trailing commas before ]
                json_array_str = json_array_str.replace(',\n        ]', ']').replace(',]', ']')
                try:
                    objs = json.loads(json_array_str)
                    technique_objects.extend(objs)
                except json.JSONDecodeError:
                    # Try parsing individual objects
                    for obj_str in entry.split('},\n        {'):
                        obj_str = obj_str.strip().rstrip(',').strip()
                        if not obj_str.startswith('{'):
                            obj_str = '{' + obj_str
                        if not obj_str.endswith('}'):
                            obj_str = obj_str + '}'
                        try:
                            obj = json.loads(obj_str)
                            technique_objects.append(obj)
                        except json.JSONDecodeError:
                            continue
            else:
                # Single technique object
                if not entry.endswith('}'):
                    entry = entry + '}'
                try:
                    obj = json.loads(entry)
                    technique_objects.append(obj)
                except json.JSONDecodeError:
                    continue

    if not technique_objects:
        return False

    # Deduplicate by (techniqueID, tactic) tuple
    seen = set()
    unique_techniques = []
    for obj in technique_objects:
        key = (obj.get("techniqueID", ""), obj.get("tactic", ""))
        if key not in seen:
            seen.add(key)
            unique_techniques.append(obj)

    # Build the complete Navigator layer structure
    layer = {
        "name": case,
        "versions": {
            "attack": "13",
            "navigator": "5.1.0",
            "layer": "4.5"
        },
        "domain": "enterprise-attack",
        "description": "",
        "filters": {
            "platforms": ["Linux", "macOS", "Windows", "Containers"]
        },
        "sorting": 0,
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": False,
            "showName": True,
            "showAggregateScores": False,
            "countUnscored": False
        },
        "hideDisabled": False,
        "techniques": unique_techniques,
        "gradient": {
            "colors": ["#ff6666ff", "#ffe766ff", "#8ec843ff"],
            "minValue": 0,
            "maxValue": 100
        },
        "legendItems": [{
            "label": "Evidence of",
            "color": "#00acb4"
        }],
        "metadata": [],
        "showTacticRowBackground": False,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False
    }

    final_path = f"{nav_assets_dir}/{case}.json"

    try:
        with open(final_path, "w") as f:
            json.dump(layer, f, indent=4)

        # Write config.json
        write_navigator_config(case, nav_assets_dir)

        # Copy to output directory
        if output_directory:
            nav_dest = os.path.join(output_directory, f"{case}_navigator.json")
            try:
                shutil.copy2(final_path, nav_dest)
                print(f"     Navigator layer copied to: {nav_dest}")
            except Exception as e:
                print(f"     Warning: Could not copy Navigator JSON: {str(e)[:100]}")

        return True

    except Exception as e:
        print(f"     Error writing Navigator layer: {e}")
        return False


def write_navigator_config(case: str, nav_assets_dir: str):
    """Write Navigator config.json."""
    config_path = f"{nav_assets_dir}/config.json"

    config = {
        "versions": {
            "enabled": True,
            "entries": [{
                "name": "ATT&CK v13",
                "version": "13",
                "domains": [{
                    "name": "Enterprise",
                    "identifier": "enterprise-attack",
                    "data": ["assets/enterprise-attack.json"]
                }]
            }]
        },
        "custom_context_menu_items": [],
        "default_layers": {
            "enabled": True,
            "urls": [f"assets/{case}.json"]
        },
        "comment_color": "yellow",
        "link_color": "blue",
        "metadata_color": "purple",
        "banner": "",
        "customize_features": [
            {"name": "multiselect", "enabled": True, "description": ""},
            {"name": "export_render", "enabled": True, "description": ""},
            {"name": "export_excel", "enabled": True, "description": ""},
            {"name": "legend", "enabled": True, "description": ""},
            {"name": "background_color", "enabled": True, "description": ""},
            {"name": "non_aggregate_score_color", "enabled": True, "description": ""},
            {"name": "aggregate_score_color", "enabled": True, "description": ""},
            {"name": "comment_underline", "enabled": True, "description": ""},
            {"name": "metadata_underline", "enabled": True, "description": ""},
            {"name": "link_underline", "enabled": True, "description": ""}
        ],
        "features": [
            {"name": "leave_site_dialog", "enabled": True, "description": ""},
            {"name": "tabs", "enabled": True, "description": ""},
            {"name": "header", "enabled": True, "description": ""},
            {"name": "selection_controls", "enabled": True, "description": "",
             "subfeatures": [
                {"name": "search", "enabled": True, "display_name": "search & multiselect", "description": ""},
                {"name": "deselect_all", "enabled": True, "display_name": "deselect techniques", "description": ""},
                {"name": "selecting_techniques", "enabled": True, "display_name": "selection behavior", "description": ""}
             ]},
            {"name": "layer_controls", "enabled": True, "description": "",
             "subfeatures": [
                {"name": "layer_settings", "enabled": True, "display_name": "layer settings", "description": ""},
                {"name": "download_layer", "enabled": True, "display_name": "export", "description": ""},
                {"name": "filters", "enabled": True, "display_name": "filters", "description": ""},
                {"name": "sorting", "enabled": True, "display_name": "sorting", "description": ""},
                {"name": "color_setup", "enabled": True, "display_name": "color setup", "description": ""},
                {"name": "toggle_hide_disabled", "enabled": True, "display_name": "show/hide disabled", "description": ""},
                {"name": "subtechniques", "enabled": True, "display_name": "sub-techniques", "description": ""}
             ]},
            {"name": "technique_controls", "enabled": True, "description": "",
             "subfeatures": [
                {"name": "disable_techniques", "enabled": True, "display_name": "toggle state", "description": ""},
                {"name": "manual_color", "enabled": True, "display_name": "background color", "description": ""},
                {"name": "scoring", "enabled": True, "display_name": "scoring", "description": ""},
                {"name": "comments", "enabled": True, "display_name": "comment", "description": ""},
                {"name": "links", "enabled": True, "display_name": "link", "description": ""},
                {"name": "metadata", "enabled": True, "display_name": "metadata", "description": ""},
                {"name": "clear_annotations", "enabled": True, "display_name": "clear annotations on selected", "description": ""}
             ]},
            {"name": "toolbar_controls", "enabled": True, "description": "",
             "subfeatures": [
                {"name": "sticky_toolbar", "enabled": True, "description": ""}
             ]}
        ]
    }

    with open(config_path, "w") as f:
        json.dump(config, f, indent=2)


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
    nav_assets_dir = "/navigator/dist/assets"
    if not os.path.exists(nav_assets_dir):
        print(f" -> {datetime.now().isoformat().replace('T', ' ')} -> ATT&CK Navigator not installed - skipping")
        print(f"     (Navigator assets directory not found: {nav_assets_dir})")
        return ""

    foundtechniques = []

    # Read techniques from CASE-level mitre_techniques.txt file
    # (All modules now write to a single consolidated file at case level)
    if output_directory:
        all_techniques = set()

        # Check for case-level techniques file (alongside dernvale_audit.log)
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

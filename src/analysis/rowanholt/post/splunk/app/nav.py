#!/usr/bin/env python3 -tt
"""
Navigation Menu Generator for Elrond Splunk App

Generates the navigation menu structure: every technique that has a dashboard
(views/xml/techniques.py), under each tactic ATT&CK v20.1 gives it, the tactics in
kill-chain order. v20 split Defense Evasion into Stealth and Defense Impairment.
"""

from typing import Dict, List

from rowanholt.post.mitre import attack_lookup
from rowanholt.post.splunk.app.views.xml.techniques import TECHNIQUES, technique_tactics


def techniques_by_tactic() -> Dict[str, List[str]]:
    """Each Enterprise tactic, in kill-chain order, with the parent techniques (view names,
    "t1059") that have a dashboard and that ATT&CK v20.1 files under it."""
    grouped: Dict[str, List[str]] = {tactic: [] for tactic in attack_lookup.ENTERPRISE_TACTICS}
    for technique_id in TECHNIQUES:
        if "." in technique_id:
            continue
        for tactic in technique_tactics(technique_id):
            if tactic in grouped:
                grouped[tactic].append(technique_id.lower())
    return {tactic: ids for tactic, ids in grouped.items() if ids}


TECHNIQUES_BY_TACTIC = techniques_by_tactic()


def create_nav_menu(defaultnav):
    """Create the ATT&CK navigation menu with all techniques organized by tactic."""

    # Techniques collection containing tactics with techniques under each
    defaultnav.write('<collection label="Techniques">\n\t\t')

    # Each tactic as a sub-collection with techniques under it
    for tactic, techniques in TECHNIQUES_BY_TACTIC.items():
        # HTML escape the ampersand in "Command and Control"
        tactic_label = tactic.replace("&", "&amp;")
        defaultnav.write(f'<collection label="{tactic_label}">\n\t\t\t')

        for technique_id in techniques:
            defaultnav.write(f'<view name="{technique_id}" />\n\t\t\t')

        defaultnav.write('</collection>\n\t\t')

    defaultnav.write('</collection>\n\t')


def get_all_technique_ids():
    """Return a flat list of all technique IDs for XML generation."""
    all_techniques = []
    for techniques in TECHNIQUES_BY_TACTIC.values():
        all_techniques.extend(techniques)
    # Remove duplicates while preserving order
    seen = set()
    unique_techniques = []
    for t in all_techniques:
        if t not in seen:
            seen.add(t)
            unique_techniques.append(t)
    return unique_techniques

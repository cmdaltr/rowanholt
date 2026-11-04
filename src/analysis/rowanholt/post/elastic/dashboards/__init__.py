#!/usr/bin/env python3 -tt
"""
Elastic/Kibana Dashboard Generator for Elrond DFIR

Generates Kibana dashboards equivalent to the Splunk dashboards,
including MITRE ATT&CK technique dashboards and overview panels.
"""

from .generator import (
    generate_all_dashboards,
    generate_mitre_overview_dashboard,
    generate_technique_dashboards,
    export_dashboards_to_ndjson,
)
from .techniques import TECHNIQUES, get_technique_by_id

__all__ = [
    'generate_all_dashboards',
    'generate_mitre_overview_dashboard',
    'generate_technique_dashboards',
    'export_dashboards_to_ndjson',
    'TECHNIQUES',
    'get_technique_by_id',
]

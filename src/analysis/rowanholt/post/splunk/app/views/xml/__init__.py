#!/usr/bin/env python3
"""
MITRE ATT&CK XML Dashboard View Generators

This package provides functions to generate XML dashboard views for
each MITRE ATT&CK tactic category.
"""

from rowanholt.post.splunk.app.views.xml.techniques import (
    create_initial_access_xml,
    create_execution_xml,
    create_persistence_xml,
    create_privilege_escalation_xml,
    create_stealth_xml,
    create_defense_impairment_xml,
    create_credential_access_xml,
    create_discovery_xml,
    create_lateral_movement_xml,
    create_collection_xml,
    create_command_and_control_xml,
    create_exfiltration_xml,
    create_impact_xml,
    create_all_technique_xmls,
    TECHNIQUES,
)

__all__ = [
    'create_initial_access_xml',
    'create_execution_xml',
    'create_persistence_xml',
    'create_privilege_escalation_xml',
    'create_stealth_xml',
    'create_defense_impairment_xml',
    'create_credential_access_xml',
    'create_discovery_xml',
    'create_lateral_movement_xml',
    'create_collection_xml',
    'create_command_and_control_xml',
    'create_exfiltration_xml',
    'create_impact_xml',
    'create_all_technique_xmls',
    'TECHNIQUES',
]

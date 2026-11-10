#!/usr/bin/env python3 -tt
"""
Splunk View Generators for the Elrond App

This module provides functions to generate all dashboard views including:
- Static utility pages (ASCII, ports, subnetting)
- MITRE ATT&CK technique HTML info pages
- MITRE ATT&CK technique XML dashboards
"""

from rowanholt.post.splunk.app.views.pages import create_ascii
from rowanholt.post.splunk.app.views.pages import create_ports
from rowanholt.post.splunk.app.views.pages import create_subnet

# Try to import HTML view modules - they may not be installed
try:
    from rowanholt.post.splunk.app.views.html.initial_access import (
        create_initial_access_html,
    )
    from rowanholt.post.splunk.app.views.html.execution import create_execution_html
    from rowanholt.post.splunk.app.views.html.persistence import create_persistence_html
    from rowanholt.post.splunk.app.views.html.privilege_escalation import (
        create_privilege_escalation_html,
    )
    from rowanholt.post.splunk.app.views.html.stealth import create_stealth_html
    from rowanholt.post.splunk.app.views.html.defense_impairment import (
        create_defense_impairment_html,
    )
    from rowanholt.post.splunk.app.views.html.credential_access import (
        create_credential_access_html,
    )
    from rowanholt.post.splunk.app.views.html.discovery import create_discovery_html
    from rowanholt.post.splunk.app.views.html.lateral_movement import (
        create_lateral_movement_html,
    )
    from rowanholt.post.splunk.app.views.html.collection import create_collection_html
    from rowanholt.post.splunk.app.views.html.command_and_control import (
        create_command_and_control_html,
    )
    from rowanholt.post.splunk.app.views.html.exfiltration import create_exfiltration_html
    from rowanholt.post.splunk.app.views.html.impact import create_impact_html
    HTML_MODULES_AVAILABLE = True
except ImportError:
    HTML_MODULES_AVAILABLE = False
    create_initial_access_html = None
    create_execution_html = None
    create_persistence_html = None
    create_privilege_escalation_html = None
    create_stealth_html = None
    create_defense_impairment_html = None
    create_credential_access_html = None
    create_discovery_html = None
    create_lateral_movement_html = None
    create_collection_html = None
    create_command_and_control_html = None
    create_exfiltration_html = None
    create_impact_html = None

# Import XML view modules from techniques.py
try:
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
    )
    XML_MODULES_AVAILABLE = True
except ImportError:
    XML_MODULES_AVAILABLE = False
    create_initial_access_xml = None
    create_execution_xml = None
    create_persistence_xml = None
    create_privilege_escalation_xml = None
    create_stealth_xml = None
    create_defense_impairment_xml = None
    create_credential_access_xml = None
    create_discovery_xml = None
    create_lateral_movement_xml = None
    create_collection_xml = None
    create_command_and_control_xml = None
    create_exfiltration_xml = None
    create_impact_xml = None
    create_all_technique_xmls = None


def create_htmls(sd):
    """
    Generate HTML information pages for MITRE ATT&CK techniques.

    Args:
        sd: The static directory path where HTML files will be created
    """
    # Skip if HTML modules are not available
    if not HTML_MODULES_AVAILABLE:
        return

    header = '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">\n<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">\n  <head>\n    <p><font size="3"><strong>Description</strong></font></p>\n      '
    headings = '</li>\n      </ul>\n  </head>\n  <body>\n    <p><br></p><p><font size="3"><strong>Information</strong></font></p>\n    <table id="mitre">\n      <tr>\n        <th width="5%">ID</th>\n        <th width="15%">Operating Systems</th>\n        <th width="30%">Tactics</th>\n        <th width="50%">Detection</th>\n      </tr>\n      <tr>\n        <td>'
    footer = '</td>\n      </tr>\n    </table>\n    <br/>\n    <table id="break">\n      <tr>\n        <th></th>\n      </tr>\n    </table>\n  </body>\n</html>'
    create_initial_access_html(sd, header, headings, footer)
    create_execution_html(sd, header, headings, footer)
    create_persistence_html(sd, header, headings, footer)
    create_privilege_escalation_html(sd, header, headings, footer)
    create_stealth_html(sd, header, headings, footer)
    create_defense_impairment_html(sd, header, headings, footer)
    create_credential_access_html(sd, header, headings, footer)
    create_discovery_html(sd, header, headings, footer)
    create_lateral_movement_html(sd, header, headings, footer)
    create_collection_html(sd, header, headings, footer)
    create_command_and_control_html(sd, header, headings, footer)
    create_exfiltration_html(sd, header, headings, footer)
    create_impact_html(sd, header, headings, footer)


def create_static_pages(sd):
    """
    Generate static utility pages.

    Args:
        sd: The static directory path where pages will be created
    """
    create_ascii(sd)
    create_ports(sd)
    create_subnet(sd)


def create_xmls(sd):
    """
    Generate XML dashboard views for MITRE ATT&CK techniques.

    Args:
        sd: The views directory path where XML files will be created
    """
    # Skip if XML modules are not available
    if not XML_MODULES_AVAILABLE:
        print("    Note: XML technique view modules not available, skipping technique dashboards")
        return

    # Generate all technique dashboards at once
    if create_all_technique_xmls:
        count = create_all_technique_xmls(sd)
        print(f"    Generated {count} MITRE ATT&CK technique dashboards")
    else:
        # Fall back to individual tactic functions
        create_initial_access_xml(sd)
        create_execution_xml(sd)
        create_persistence_xml(sd)
        create_privilege_escalation_xml(sd)
        create_stealth_xml(sd)
        create_defense_impairment_xml(sd)
        create_credential_access_xml(sd)
        create_discovery_xml(sd)
        create_lateral_movement_xml(sd)
        create_collection_xml(sd)
        create_command_and_control_xml(sd)
        create_exfiltration_xml(sd)
        create_impact_xml(sd)
